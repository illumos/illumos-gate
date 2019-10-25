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
#include <fcntl.h>
#include <unistd.h>
#include <sys/procfs.h>

static int my_id;
static int my_fd = -2;

static unsigned long max_size;

unsigned long get_mem_kb(void)
{
	prpsinfo_t pbuf;

	if (my_fd == -2) {
		/* Do not repeatedly attempt this if it fails. */
		my_fd = open("/proc/self/psinfo", O_RDONLY);
	}
	if (my_fd == -1) {
		return (0);
	}

	if (pread(my_fd, &pbuf, sizeof (pbuf), 0) != sizeof (pbuf)) {
		return (0);
	}

	return (pbuf.pr_rssize);
}

static void match_end_func(struct symbol *sym)
{
	unsigned long size;

	if (option_mem) {
		size = get_mem_kb();
		if (size > max_size)
			max_size = size;
	}
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
