/*
 * Copyright (C) 2010 Dan Carpenter.
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

static int my_id;

/* this is stolen from the kernel but it's totally fair use dude...  */
#define __GFP_DMA       (0x01u)
#define __GFP_HIGHMEM   (0x02u)
#define __GFP_DMA32     (0x04u)
#define __GFP_MOVABLE   (0x08u)
#define GFP_ZONEMASK    (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)

static void match_alloc(const char *fn, struct expression *expr, void *_arg)
{
	int arg_nr = PTR_INT(_arg);
	struct expression *arg_expr;
	sval_t sval;

	arg_expr = get_argument_from_call_expr(expr->args, arg_nr);
	if (!get_value(arg_expr, &sval))
		return;
	if (sval.uvalue == 0) /* GFP_NOWAIT */
		return;
	if (!(sval.uvalue & ~GFP_ZONEMASK))
		sm_error("no modifiers for allocation.");
}

void check_gfp_dma(int id)
{
	my_id = id;
	if (option_project != PROJ_KERNEL)
		return;
	add_function_hook("kmalloc", &match_alloc, INT_PTR(1));
	add_function_hook("kzalloc", &match_alloc, INT_PTR(1));
}
