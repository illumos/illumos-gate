/*
 * Copyright (C) 2013 Oracle.
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
 * This tries to find buffer overflows in sprintf().
 * I'll freely admit that the code is sort of crap.
 * Also if it sees "sprintf("%2d\n", x)" then it assumes x is less than 99.
 * That might not be true so there maybe buffer overflows which are missed.
 *
 */

#include <ctype.h>
#include "smatch.h"

static int my_id;

struct param_info {
	int buf_or_limit;
	int string;
};

struct param_info zero_one = {0, 1};

static int handle_format(struct expression *call, char **pp, int *arg_nr)
{
	struct expression *arg;
	char *p = *pp;
	int ret = 1;
	char buf[256];
	sval_t max;

	p++;  /* we passed it with *p == '%' */

	if (*p == '%') {
		p++;
		ret = 1;
		goto out_no_arg;
	}
	if (*p == 'c') {
		p++;
		ret = 1;
		goto out;
	}


	if (isdigit(*p) || *p == '.') {
		unsigned long num;

		if (*p == '.')
			p++;

		num = strtoul(p, &p, 10);
		ret = num;

		while (*p == 'l')
			p++;
		p++; /* eat the 'd' char */
		goto out;
	}

	if (*p == 'l') {
		p++;
		if (*p == 'l')
			p++;
	}

	if (option_project == PROJ_KERNEL && *p == 'z')
		p++;

	if (option_project == PROJ_KERNEL && *p == 'p') {
		if (*(p + 1) == 'I' || *(p + 1) == 'i') {
			char *eye;

			eye = p + 1;
			p += 2;
			if (*p == 'h' || *p == 'n' || *p == 'b' || *p == 'l')
				p++;
			if (*p == '4') {
				p++;
				ret = 15;
				goto out;
			}
			if (*p == '6') {
				p++;
				if (*p == 'c')
					p++;
				if (*eye == 'I')
					ret = 39;
				if (*eye == 'i')
					ret = 32;
				goto out;
			}
		}
		if (*(p + 1) == 'M') {
			p += 2;
			if (*p == 'R' || *p == 'F')
				p++;
			ret = 17;
			goto out;
		}
		if (*(p + 1) == 'm') {
			p += 2;
			if (*p == 'R')
				p++;
			ret = 12;
			goto out;
		}
	}

	arg = get_argument_from_call_expr(call->args, *arg_nr);
	if (!arg)
		goto out;

	if (*p == 's') {
		ret = get_array_size_bytes(arg);
		if (ret < 0)
			ret = 1;
		/* we don't print the NUL here */
		ret--;
		p++;
		goto out;
	}

	if (*p != 'd' && *p != 'i' && *p != 'x' && *p != 'X' && *p != 'u' && *p != 'p') {
		ret = 1;
		p++;
		goto out;
	}

	get_absolute_max(arg, &max);

	if (*p == 'x' || *p == 'X' || *p == 'p') {
		ret = snprintf(buf, sizeof(buf), "%llx", max.uvalue);
	} else if (*p == 'u') {
		ret = snprintf(buf, sizeof(buf), "%llu", max.uvalue);
	} else if (!expr_unsigned(arg)) {
		sval_t min;
		int tmp;

		ret = snprintf(buf, sizeof(buf), "%lld", max.value);
		get_absolute_min(arg, &min);
		tmp = snprintf(buf, sizeof(buf), "%lld", min.value);
		if (tmp > ret)
			ret = tmp;
	} else {
		ret = snprintf(buf, sizeof(buf), "%lld", max.value);
	}
	p++;

out:
	(*arg_nr)++;
out_no_arg:
	*pp = p;
	return ret;
}

int get_formatted_string_size(struct expression *call, int arg)
{
	struct expression *expr;
	char *p;
	int count;

	expr = get_argument_from_call_expr(call->args, arg);
	if (!expr || expr->type != EXPR_STRING)
		return -1;

	arg++;
	count = 0;
	p = expr->string->data;
	while (*p) {

		if (*p == '%') {
			count += handle_format(call, &p, &arg);
		} else if (*p == '\\') {
			p++;
		}else {
			p++;
			count++;
		}
	}

	count++; /* count the NUL terminator */
	return count;
}

static void match_not_limited(const char *fn, struct expression *call, void *info)
{
	struct param_info *params = info;
	struct range_list *rl;
	struct expression *dest;
	struct expression *arg;
	int buf_size, size;
	int user = 0;
	int i;
	int offset = 0;

	dest = get_argument_from_call_expr(call->args, params->buf_or_limit);
	dest = strip_expr(dest);
	if (dest->type == EXPR_BINOP && dest->op == '+') {
		sval_t max;

		if (get_hard_max(dest->right, &max))
			offset = max.value;
		dest = dest->left;
	}


	buf_size = get_array_size_bytes(dest);
	if (buf_size <= 0)
		return;

	size = get_formatted_string_size(call, params->string);
	if (size <= 0)
		return;
	if (size < offset)
		size -= offset;
	if (size <= buf_size)
		return;

	i = 0;
	FOR_EACH_PTR(call->args, arg) {
		if (i++ <= params->string)
			continue;
		if (get_user_rl(arg, &rl))
			user = 1;
	} END_FOR_EACH_PTR(arg);

	sm_error("format string overflow. buf_size: %d length: %d%s",
	       buf_size, size, user ? " [user data]": "");
}

void check_string_len(int id)
{
	my_id = id;
	add_function_hook("sprintf", &match_not_limited, &zero_one);
}

