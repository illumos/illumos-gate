/*
 * Copyright (C) 2018 Oracle.
 * Copyright 2019 Joyent, Inc.
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
#ifdef __sun
#include <sys/procfs.h>
#endif

static int my_id;

static unsigned long max_size;

#ifdef __sun
unsigned long get_mem_kb(void)
{
	static int my_fd = -2;
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
#else
unsigned long get_mem_kb(void)
{
	FILE *file;
	char buf[1024] = "0";
	unsigned long size;

	file = fopen("/proc/self/statm", "r");
	if (!file)
	        return 0;
	fread(buf, 1, sizeof(buf), file);
	fclose(file);

	size = strtoul(buf, NULL, 10);
	size = size * sysconf(_SC_PAGESIZE) / 1024;
	return size;
}
#endif

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
