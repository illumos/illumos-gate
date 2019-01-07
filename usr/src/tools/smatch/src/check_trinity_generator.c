/*
 * Copyright (C) 2017 Oracle.
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
 * The idea is to generate syscall templates for the Trinity fuzzer.  There
 * isn't currently quite enough information to do it right but I want to start
 * and see how far I can get.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

FILE *sysc_fd;

static int gen_custom_struct(int nr, struct symbol *arg)
{
	return 0;
}

static void print_arg(int nr, struct symbol *arg)
{
	fprintf(sysc_fd, "\t.arg%dname = \"%s\",\n", nr + 1, arg->ident->name);
	fprintf(sysc_fd, "\t.arg%dtype = %s,\n", nr + 1, get_syscall_arg_type(arg));
}

static void match_return(struct expression *ret_value)
{
	struct symbol *arg;
	int num_args;
	char *name;
	int i;
	char buf[256];
	int has_custom_struct[6];

	if (!get_function() || !cur_func_sym)
		return;
	if (strncmp(get_function(), "SYSC_", 5) != 0)
		return;

	num_args = ptr_list_size((struct ptr_list *)cur_func_sym->ctype.base_type->arguments);
	name = get_function() + 5;

	snprintf(buf, sizeof(buf), "smatch_trinity_%s", name);
	sysc_fd = fopen(buf, "w");
	if (!sm_outfd) {
		printf("Error:  Cannot open %s\n", buf);
		return;
	}

	i = 0;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		if (gen_custom_struct(i, arg))
			has_custom_struct[i] = true;
		else
			has_custom_struct[i] = false;
		i++;
	} END_FOR_EACH_PTR(arg);

	fprintf(sysc_fd, "struct syscallentry sm_%s = {\n", name);
	fprintf(sysc_fd, "\t.name = \"%s\",\n", name);
	fprintf(sysc_fd, "\t.num_args = %d,\n", num_args);

	i = 0;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		if (has_custom_struct[i])
			;
		else
			print_arg(i++, arg);
	} END_FOR_EACH_PTR(arg);

	fprintf(sysc_fd, "};\n");
}

void check_trinity_generator(int id)
{
	my_id = id;

	if (option_project != PROJ_KERNEL)
		return;
	add_hook(&match_return, RETURN_HOOK);
}
