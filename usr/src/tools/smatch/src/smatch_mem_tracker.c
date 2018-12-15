/*
 * Copyright (C) 2018 Oracle.
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
#include <unistd.h>

static int my_id;

static unsigned long max_size;

static void match_end_func(struct symbol *sym)
{
	FILE *file;
	char buf[1024];
	unsigned long size;

	file = fopen("/proc/self/statm", "r");
	if (!file)
		return;
	fread(buf, 1, sizeof(buf), file);
	fclose(file);

	size = strtoul(buf, NULL, 10);
	size = size * sysconf(_SC_PAGESIZE) / 1024;
	if (size > max_size)
		max_size = size;
}

unsigned long get_max_memory(void)
{
	return max_size;
}

void register_mem_tracker(int id)
{
	my_id = id;

	add_hook(&match_end_func, END_FUNC_HOOK);
}
