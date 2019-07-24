/*
 * Copyright (C) 2006 Dan Carpenter.
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
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "check_list.h"

char *option_debug_check = (char *)"";
char *option_project_str = (char *)"smatch_generic";
static char *option_db_file = (char *)"smatch_db.sqlite";
enum project_type option_project = PROJ_NONE;
char *bin_dir;
char *data_dir;
int option_no_data = 0;
int option_spammy = 0;
int option_info = 0;
int option_full_path = 0;
int option_param_mapper = 0;
int option_call_tree = 0;
int option_no_db = 0;
int option_enable = 0;
int option_disable = 0;
int option_file_output;
int option_time;
int option_mem;
char *option_datadir_str;
int option_fatal_checks;
int option_succeed;
int option_timeout = 60;

FILE *sm_outfd;
FILE *sql_outfd;
FILE *caller_info_fd;

int sm_nr_errors;
int sm_nr_checks;

bool __silence_warnings_for_stmt;

const char *progname;

typedef void (*reg_func) (int id);
#define CK(_x) {.name = #_x, .func = &_x, .enabled = 0},
static struct reg_func_info {
	const char *name;
	reg_func func;
	int enabled;
} reg_funcs[] = {
	{NULL, NULL},
#include "check_list.h"
};
#undef CK
int num_checks = ARRAY_SIZE(reg_funcs) - 1;

const char *check_name(unsigned short id)
{
	if (id >= ARRAY_SIZE(reg_funcs))
		return "internal";

	return reg_funcs[id].name;
}

int id_from_name(const char *name)
{
	int i;

	for (i = 1; i < ARRAY_SIZE(reg_funcs); i++) {
		if (!strcmp(name, reg_funcs[i].name))
			return i;
	}
	return 0;
}

static void show_checks(void)
{
	int i;

	for (i = 1; i < ARRAY_SIZE(reg_funcs); i++) {
		if (!strncmp(reg_funcs[i].name, "check_", 6))
			printf("%3d. %s\n", i, reg_funcs[i].name);
	}
	exit(0);
}

static void enable_disable_checks(char *s, bool enable)
{
	char buf[128];
	char *next;
	int i;

	do {
		next = strchr(s, ',');
		if (next) {
			*next = '\0';
			next++;
		}
		if (*s == '\0')
			return;
		if (strncmp(s, "check_", 6) == 0)
			snprintf(buf, sizeof(buf), "%s", s);
		else
			snprintf(buf, sizeof(buf), "check_%s", s);


		for (i = 1; i < ARRAY_SIZE(reg_funcs); i++) {
			if (strcmp(reg_funcs[i].name, buf) == 0) {
				reg_funcs[i].enabled = (enable == true) ? 1 : -1;
				break;
			}
		}

		if (i == ARRAY_SIZE(reg_funcs))
			sm_fatal("'%s' not found", s);

	} while ((s = next));
}

static void help(void)
{
	printf("Usage:  smatch [smatch arguments][sparse arguments] file.c\n");
	printf("--project=<name> or -p=<name>: project specific tests\n");
	printf("--succeed: don't exit with an error\n");
	printf("--spammy:  print superfluous crap.\n");
	printf("--info:  print info used to fill smatch_data/.\n");
	printf("--debug:  print lots of debug output.\n");
	printf("--param-mapper:  enable param_mapper output.\n");
	printf("--no-data:  do not use the /smatch_data/ directory.\n");
	printf("--data=<dir>: overwrite path to default smatch data directory.\n");
	printf("--full-path:  print the full pathname.\n");
	printf("--debug-implied:  print debug output about implications.\n");
	printf("--assume-loops:  assume loops always go through at least once.\n");
	printf("--two-passes:  use a two pass system for each function.\n");
	printf("--file-output:  instead of printing stdout, print to \"file.c.smatch_out\".\n");
	printf("--fatal-checks: check output is treated as an error.\n");
	printf("--help:  print this helpful message.\n");
	exit(1);
}

static int match_option(const char *arg, const char *option)
{
	char *str;
	char *tmp;
	int ret = 0;

	str = malloc(strlen(option) + 3);
	snprintf(str, strlen(option) + 3, "--%s", option);
	tmp = str;
	while (*tmp) {
		if (*tmp == '_')
			*tmp = '-';
		tmp++;
	}
	if (!strcmp(arg, str))
		ret = 1;
	free(str);
	return ret;
}

#define OPTION(_x) do {					\
	if (match_option((*argvp)[i], #_x)) { 		\
		option_##_x = 1;			\
	}                                               \
} while (0)

void parse_args(int *argcp, char ***argvp)
{
	int i;

	for (i = 1 ; i < *argcp; i++) {
		if (!strcmp((*argvp)[i], "--help"))
			help();

		if (!strcmp((*argvp)[i], "--show-checks"))
			show_checks();

		if (!strncmp((*argvp)[i], "--project=", 10))
			option_project_str = (*argvp)[i] + 10;

		if (!strncmp((*argvp)[i], "-p=", 3))
			option_project_str = (*argvp)[i] + 3;

		if (!strncmp((*argvp)[i], "--db-file=", 10))
			option_db_file = (*argvp)[i] + 10;

		if (!strncmp((*argvp)[i], "--data=", 7))
			option_datadir_str = (*argvp)[i] + 7;

		if (!strncmp((*argvp)[i], "--debug=", 8))
			option_debug_check = (*argvp)[i] + 8;

		if (strncmp((*argvp)[i], "--trace=", 8) == 0)
			trace_variable = (*argvp)[i] + 8;

		if (strncmp((*argvp)[i], "--enable=", 9) == 0) {
			enable_disable_checks((*argvp)[i] + 9, 1);
			option_enable = 1;
		}

		if (strncmp((*argvp)[i], "--disable=", 10) == 0) {
			enable_disable_checks((*argvp)[i] + 10, 0);
			option_enable = 1;
			option_disable = 1;
		}

		if (!strncmp((*argvp)[i], "--timeout=", 10)) {
			if (sscanf((*argvp)[i] + 10, "%d",
			    &option_timeout) != 1)
				sm_fatal("invalid option %s", (*argvp)[i]);
		}

		OPTION(fatal_checks);
		OPTION(spammy);
		OPTION(info);
		OPTION(debug);
		OPTION(assume_loops);
		OPTION(no_data);
		OPTION(two_passes);
		OPTION(full_path);
		OPTION(param_mapper);
		OPTION(call_tree);
		OPTION(file_output);
		OPTION(time);
		OPTION(mem);
		OPTION(no_db);
		OPTION(succeed);
	}

	if (strcmp(option_project_str, "smatch_generic") != 0)
		option_project = PROJ_UNKNOWN;

	if (strcmp(option_project_str, "kernel") == 0)
		option_project = PROJ_KERNEL;
	else if (strcmp(option_project_str, "wine") == 0)
		option_project = PROJ_WINE;
	else if (strcmp(option_project_str, "illumos_kernel") == 0)
		option_project = PROJ_ILLUMOS_KERNEL;
	else if (strcmp(option_project_str, "illumos_user") == 0)
		option_project = PROJ_ILLUMOS_USER;
}

static char *read_bin_filename(void)
{
	char filename[PATH_MAX] = {};
	char proc[PATH_MAX];

	pid_t pid = getpid();
	sprintf(proc, "/proc/%d/exe", pid);
	if (readlink(proc, filename, PATH_MAX) < 0)
		return NULL;
	return alloc_string(filename);
}

static char *get_bin_dir(char *arg0)
{
	char *orig;

	orig = read_bin_filename();
	if (!orig)
		orig = alloc_string(arg0);
	return dirname(orig);
}

static char *get_data_dir(char *arg0)
{
	char buf[256];
	char *dir;

	if (option_no_data)
		return NULL;

	if (option_datadir_str) {
		if (access(option_datadir_str, R_OK))
			sm_warning("%s is not accessible -- ignored.",
					option_datadir_str);
		else
			return alloc_string(option_datadir_str);
	}

	strncpy(buf, "smatch_data/", sizeof(buf));
	dir = alloc_string(buf);
	if (!access(dir, R_OK))
		return dir;

	strncpy(buf, bin_dir, 254);

	buf[255] = '\0';
	strncat(buf, "/smatch_data/", 254 - strlen(buf));
	dir = alloc_string(buf);
	if (!access(dir, R_OK))
		return dir;
	free_string(dir);
	snprintf(buf, 254, "%s/smatch_data/", SMATCHDATADIR);
	dir = alloc_string(buf);
	if (!access(dir, R_OK))
		return dir;

	sm_warning("%s is not accessible.", dir);
	sm_warning("Use --no-data or --data to suppress this message.");
	return NULL;
}

int main(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	int i;
	reg_func func;

	sm_outfd = stdout;
	sql_outfd = stdout;
	caller_info_fd = stdout;

	progname = argv[0];

	parse_args(&argc, &argv);

	if (argc < 2)
		help();

	/* this gets set back to zero when we parse the first function */
	final_pass = 1;

	bin_dir = get_bin_dir(argv[0]);
	data_dir = get_data_dir(argv[0]);

	allocate_hook_memory();
	allocate_dynamic_states_array(num_checks);
	create_function_hook_hash();
	open_smatch_db(option_db_file);
	sparse_initialize(argc, argv, &filelist);
	alloc_valid_ptr_rl();

	for (i = 1; i < ARRAY_SIZE(reg_funcs); i++) {
		func = reg_funcs[i].func;
		/* The script IDs start at 1.
		   0 is used for internal stuff. */
		if (!option_enable || reg_funcs[i].enabled == 1 ||
		    (option_disable && reg_funcs[i].enabled != -1) ||
		    strncmp(reg_funcs[i].name, "register_", 9) == 0)
			func(i);
	}

	smatch(filelist);
	free_string(data_dir);

	if (option_succeed)
		return 0;
	if (sm_nr_errors > 0)
		return 1;
	if (sm_nr_checks > 0 && option_fatal_checks)
		return 1;
	return 0;
}
