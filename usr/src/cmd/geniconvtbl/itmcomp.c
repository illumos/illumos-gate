/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>
#include <locale.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <stdarg.h>
#include <errno.h>

#include "itmcomp.h"
#include "maptype.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
#define	ITMSUFFIX	".bt"
#define	ME_DEFAULT	"geniconvtbl"
#define	CPP_PATH	"/usr/lib/cpp"

itmc_ref_t	*ref_first[ITMC_OBJ_LAST + 1];
itmc_ref_t	*ref_last[ITMC_OBJ_LAST + 1];

itmc_name_t	*name_first;
itmc_name_t	*name_last;

char		*itm_input_file;		/* referred in itm_comp.l */
char		*itm_output_file;

cmd_opt_t	cmd_opt;
itm_num_t	name_id;
itm_num_t	reg_id;

itmc_name_t	name_lookup_error;
int		error_deferred;

char *itm_name_type_name[] = {
	"UNKNOWN",
	"ITM",
	"STRING",
	"DIRECTION",
	"CONDITION",
	"MAP",
	"OPERATION",
	"EXPRESSION",
	"DATA",
	"NAME",
	"RANGE",
	"REGISTER",
};


static void	usage(int status);
static int	cpp_opt_append(char	*opt, char	*arg);
static void	cpp_opt_trunc(int num);
static int	parse_opts(int argc, char	**argv);
static char	*prog_path_expand(const char	*base_name);
static void	map_name_type_append(char	*optarg);
static char	*map_type_name_str(itmc_map_type_t);
static char	*strdup_vital(const char *);

#if defined(ENABLE_TRACE)
static void	trace_option(void);
#endif /* ENABLE_TRACE */
static FILE	*cpp_open(void);
static void	cpp_close(FILE		*fp);
static int	itm_compile(char	*file);
static void	wait_child(pid_t pid);
static int	fork_error(void);




int
main(int argc, char **argv)
{
	char	**pp;
	pid_t	pid;

	(void) setlocale(LC_ALL, "");

	(void) textdomain(TEXT_DOMAIN);

	(void) parse_opts(argc, argv);

#if defined(ENABLE_TRACE)
	trace_option();
#endif /* ENABLE_TRACE */

	if (NULL != cmd_opt.disassemble) {
		disassemble(cmd_opt.disassemble);
	} else if (NULL == cmd_opt.input_file) {
		(void) itm_compile(NULL);
	} else {
		if (1 < cmd_opt.input_file_num) {
			for (pp = cmd_opt.input_file; *pp; pp++) {
				(void) printf("%s:\n", *pp);
				pid = fork();
				switch (pid) {
				case 0:
					exit(itm_compile(*pp));
					break;
				case -1:
					(void) fork_error();
					break;
				default:
					wait_child(pid);
				}
			}
		} else {
			(void) itm_compile(*(cmd_opt.input_file));
		}
	}

	return (0);
}


static int
itm_compile(char *file)
{
	char	*cmd_line;
	char	*command;
	char	*p;
	size_t	length;
	FILE	*fp;

	extern int	yyparse();
	extern FILE *yyin;

	if (NULL == file) {
		itm_input_file = gettext("*stdin*");
	} else {
		if (0 != access(file, R_OK)) {
			int	e = errno;
			itm_error(
				gettext("%1$s: can not access %2$s: "),
				cmd_opt.my_name, file);
			errno = e;
			PERROR(NULL);
			exit(ITMC_STATUS_CMD2);
		}
		itm_input_file = file;
	}

	if ((NULL == cmd_opt.output_file) &&
	    (0 == cmd_opt.no_output)) {
		p = strrchr(file, '.');
		if (NULL == p) {
			length = strlen(file);
		} else {
			length = p - file;
		}
		itm_output_file = malloc_vital(length + 5);
		(void) memcpy(itm_output_file, file, length);
		(void) memcpy(itm_output_file + length, ITMSUFFIX, 5);
	} else {
		itm_output_file = cmd_opt.output_file;
	}

	if (0 != cmd_opt.preprocess) {
		if (NULL == file) {
			fp = cpp_open();
			cmd_line = cmd_opt.preprocess;
		} else {
			(void) cpp_opt_append(file, NULL);
			fp = cpp_open();
			cpp_opt_trunc(1);
		}
		if (NULL == fp) {
			p = strchr(cmd_line, ' ');
			if (NULL == p) {
				length = strlen(cmd_line);
			} else {
				length = (p - cmd_line);
			}
			command = malloc_vital((sizeof (char)) * (length + 1));
			(void) memcpy(command, cmd_line, length);
			*(command + length) = '\0';
			PERROR(command);
			itm_error(
				gettext("%1$s: can not start %2$s on %3$s\n"),
				cmd_opt.my_name, command, itm_input_file);
			exit(ITMC_STATUS_SYS);
		} else {
			yyin = fp;
		}

		(void) yyparse();
		if (NULL == cmd_opt.preprocess_specified) {
			cpp_close(fp);
		}
	} else {
		if ((NULL == file) || (0 != strcmp("-", file))) {
			yyin = stdin;
		} else {
			yyin = fopen(file, "r");
			if (NULL == yyin) {
				itm_error(
					gettext("%1$s: can not open %2$s\n"),
					cmd_opt.my_name, itm_input_file);
				exit(ITMC_STATUS_CMD2);
			}
		}
		(void) yyparse();
		if (stdin != yyin) {
			(void) fclose(yyin);
		}
	}

	return (ITMC_STATUS_SUCCESS);
}




static void
wait_child(pid_t pid)
{
	int	stat_loc;
	char *msgstr;

	(void) waitpid(pid, &stat_loc, 0);
	if (WTERMSIG(stat_loc)) {
		if (WCOREDUMP(stat_loc)) {
			msgstr = gettext("signal received: %s, core dumped\n");
		} else {
			msgstr = gettext("signal received: %s\n");
		}
		itm_error(msgstr, strsignal(WTERMSIG(stat_loc)));
	}
}


static int
fork_error(void)
{
	PERROR(gettext("fork"));
	exit(ITMC_STATUS_SYS);
	return (0); /* never return */
}



static int
parse_opts(int argc, char **argv)
{
	int		c;
	int		i;
	char		*p;
	int		error_num = 0;

#ifdef YYDEBUG
	extern int	yydebug;
#endif /* YYDEBUG */

	extern char	*optarg;
	extern int	optind;


	cmd_opt.my_name = basename(*(argv + 0));
	if ('\0' == *(cmd_opt.my_name)) {
		cmd_opt.my_name = ME_DEFAULT;
	}

	cmd_opt.preprocess_default = CPP_PATH;
	cmd_opt.preprocess = cmd_opt.preprocess_default;
	cmd_opt.strip = 1; /* stripped by default */
	while ((c = getopt(argc, argv, "d:i:p:W:D:I:U:fnsM:lo:qX:h")) != EOF) {
		switch (c) {
		case 'd':
			cmd_opt.disassemble = optarg;
			break;
		case 'i':
			cmd_opt.interpreter = optarg;
			break;
		case 'p':
			if (NULL != cmd_opt.preprocess_specified) {
				(void) fprintf(stderr,
				gettext("multiple -p options are specified\n"));
				error_num += 1;
			}
			cmd_opt.preprocess_specified =
				prog_path_expand(optarg);
			cmd_opt.preprocess = cmd_opt.preprocess_specified;
			if (NULL == cmd_opt.preprocess) {
				(void) fprintf(stderr,
				gettext("cannot find preprocessor \"%s\"\n"),
					optarg);
				error_num += 1;
			}
			(void) cpp_opt_append(NULL, NULL);
			p = basename(optarg);
			if (NULL == p) {
				*(cmd_opt.cpp_opt + 0) = strdup_vital(optarg);
			} else {
				*(cmd_opt.cpp_opt + 0) = strdup_vital(p);
			}
			break;
		case 'W':
			if (cpp_opt_append(optarg, NULL)) {
				error_num += 1;
			}
			break;
		case 'I':
			if (cpp_opt_append("-I", optarg)) {
				error_num += 1;
			}
			break;
		case 'D':
			if (cpp_opt_append("-D", optarg)) {
				error_num += 1;
			}
			break;
		case 'U':
			if (cpp_opt_append("-U", optarg)) {
				error_num += 1;
			}
			break;
		case 'f':
			cmd_opt.force_overwrite = 1;
			break;
		case 'n':
			cmd_opt.no_output = 1;
			break;
		case 'M':
			map_name_type_append(optarg);
			break;
		case 'l':
			cmd_opt.large_table = 1;
			break;
		case 'o':
			cmd_opt.output_file = optarg;
			break;
		case 's':
			cmd_opt.strip = 0;
			break;
		case 'q':
			cmd_opt.quiet = 1;
			break;
#if defined(ENABLE_TRACE)
		case 'X':
			cmd_opt.trace = malloc_vital((sizeof (char)) * 128);
			(void) memset(cmd_opt.trace, 0, (sizeof (char)) * 128);
			for (p = optarg; *p; p++) {
				*(cmd_opt.trace + ((*p) & 0x007f)) = 1;
			}
#ifdef YYDEBUG
			if (TRACE('Y'))	yydebug = 1;
#endif /* YYDEBUG */
			break;
#endif /* ENABLE_TRACE */
		case 'h':
			usage(ITMC_STATUS_SUCCESS);
			break;
		default:
			usage(ITMC_STATUS_CMD);
		}
	}

	if (optind < argc) {
		cmd_opt.input_file_num = (argc - optind);
		cmd_opt.input_file =
			malloc_vital((sizeof (char *)) *
					(argc - optind + 1));
		*(cmd_opt.input_file + (argc - optind)) = NULL;
	}

	for (i = 0; optind < argc; optind++, i++) {
		*(cmd_opt.input_file + i) = argv[optind];
	}

	/* check conflict */

	if ((1 < cmd_opt.input_file_num) && (NULL != cmd_opt.output_file)) {
		itm_error(gettext("use -o with single input file\n"));
		error_num++;
	}

	if ((cmd_opt.input_file_num <= 0) &&
	    (NULL == cmd_opt.output_file) &&
	    (NULL == cmd_opt.disassemble) &&
	    (0 == cmd_opt.no_output)) {
		itm_error(gettext(
			"output file is unnamed. "
			"use -o to specify output file\n"));
		error_num++;
	}

	if (cmd_opt.disassemble &&
	    (cmd_opt.interpreter ||
	    cmd_opt.cpp_opt ||
	    cmd_opt.preprocess_specified ||
	    cmd_opt.input_file ||
	    cmd_opt.force_overwrite ||
	    cmd_opt.no_output ||
	    cmd_opt.map_name_type ||
	    cmd_opt.large_table ||
	    cmd_opt.output_file)) {
		itm_error(
			gettext("-d may not specified with other options\n"));
		error_num++;
	}

	if (error_num) {
		usage(ITMC_STATUS_CMD);
	}

	/*
	 * do not move upward
	 * may conflict with -d option
	 */
	if ((NULL == cmd_opt.preprocess_specified) &&
	    (NULL != cmd_opt.preprocess_default)) {
		(void) cpp_opt_append(NULL, NULL);
		p = basename(cmd_opt.preprocess_default);
		if (NULL == p) {
			*(cmd_opt.cpp_opt + 0) =
				strdup_vital(cmd_opt.preprocess_default);
		} else {
			*(cmd_opt.cpp_opt + 0) = strdup_vital(p);
		}
	}
	return (0);
}


static FILE *
cpp_open(void)
{
	pid_t	pid;
	int	filedes[2];
	int	i;

	for (i = 0; i < cmd_opt.cpp_opt_num; i++) {
		TRACE_MESSAGE('C', ("%s\n", *(cmd_opt.cpp_opt + i)));
	}

	if (pipe(filedes)) {
		PERROR(gettext("pipe"));
		itm_error(gettext("failed to open pipe\n"));
		exit(ITMC_STATUS_SYS);
	}
	pid = fork();
	if (pid == 0) {	/* child */
		(void) close(filedes[0]);
		(void) close(1);
		(void) dup2(filedes[1], 1);
		(void) execv(cmd_opt.preprocess, cmd_opt.cpp_opt);
		exit(0);
	} else if (pid == (pid_t)(-1)) {	/* error */
		return	(NULL);
	} else {
		(void) close(filedes[1]);
		return (fdopen(filedes[0], "r"));
	}
	return	(NULL); /* NEVER */
}


static int
cpp_opt_append(char	*opt, char	*arg)
{
	size_t	opt_len;
	size_t	arg_len;
	char	*new_opt;
	char	**new_opt_list;

	opt_len = ((NULL == opt) ? 0 : strlen(opt));
	arg_len = ((NULL == arg) ? 0 : strlen(arg));
	if (0 < (opt_len + arg_len)) {
		new_opt = malloc_vital(opt_len + arg_len + 1);
		if (NULL != opt) {
			(void) memcpy(new_opt, opt, opt_len + 1);
		}
		if (NULL != arg) {
			(void) memcpy(new_opt + opt_len, arg, arg_len + 1);
		}
	} else {
		new_opt = NULL;
	}

	if (0 == cmd_opt.cpp_opt_reserved) {
		cmd_opt.cpp_opt_reserved = 32;
		cmd_opt.cpp_opt = malloc_vital((sizeof (char *)) * 32);
		*(cmd_opt.cpp_opt + 0) = "cpp";
		cmd_opt.cpp_opt_num = 1;
	} else if ((cmd_opt.cpp_opt_reserved - 2) <= cmd_opt.cpp_opt_num) {
		cmd_opt.cpp_opt_reserved += 32;
		new_opt_list = malloc_vital((sizeof (char *)) *
					    cmd_opt.cpp_opt_reserved);
		(void) memcpy(new_opt_list, cmd_opt.cpp_opt,
			(sizeof (char *)) * cmd_opt.cpp_opt_num);
		(void) memset(new_opt_list + cmd_opt.cpp_opt_num, 0, 32);
		free(cmd_opt.cpp_opt);
		cmd_opt.cpp_opt = new_opt_list;
	}
	if (NULL != new_opt) {
		*(cmd_opt.cpp_opt + cmd_opt.cpp_opt_num) = new_opt;
		cmd_opt.cpp_opt_num += 1;
	}
	return (0);
}


static void
cpp_opt_trunc(int num)
{
	if (cmd_opt.cpp_opt_num < num) {
		num = cmd_opt.cpp_opt_num;
	}
	for (; 0 < num; --num) {
		free(cmd_opt.cpp_opt + cmd_opt.cpp_opt_num);
		--(cmd_opt.cpp_opt_num);
	}
}


static void
cpp_close(FILE *fp)
{
	(void) fclose(fp);
	(void) wait_child(0);
}




static char *
prog_path_expand(const char *base_name)
{
	size_t	base_len;
	size_t	dir_len;
	char	path[MAXPATHLEN];
	char	*p;
	char	*pe;

	base_len = strlen(base_name);
	path[0] = '\0';

	if (NULL != strchr(base_name, '/')) {
		if (0 == access(base_name, X_OK)) {
			return (strdup_vital(base_name));
		} else {
			return (NULL);
		}
	}

	for (p = getenv("PATH"); p; ) {
		pe = strchr(p, ':');
		dir_len = ((NULL == pe) ? strlen(p) : (pe - p));
		(void) memcpy(path, p, dir_len);
		if ((0 != dir_len) &&
		    ('/' != path[dir_len - 1])) {
			path[dir_len] = '/';
			dir_len += 1;
		}
		if ((dir_len + base_len) < MAXPATHLEN) {
			(void) memcpy(path + dir_len, base_name, base_len + 1);
			if (0 == access(path, X_OK)) {
				return (strdup_vital(path));
			}
		}
		p = ((NULL == pe) ? NULL : (pe + 1));
	}
	return	(NULL);
}


static void
usage(int status)
{

	if (ITMC_STATUS_SUCCESS == status) {
		(void) fprintf(stdout,
		gettext("Usage: %1$s [-n] [-f] [-q]\n"
		"	     [-p preprocessor] [-W argument]\n"
		"	     [-Dname] [-Dname=def] [-Idirectory] [-Uname]\n"
		"	     [file ...]\n	%2$s -h\n"),
		cmd_opt.my_name, cmd_opt.my_name);
	} else {
		(void) itm_error(
		gettext("Usage: %1$s [-n] [-f] [-q]\n"
		"	     [-p preprocessor] [-W argument]\n"
		"	     [-Dname] [-Dname=def] [-Idirectory] [-Uname]\n"
		"	     [file ...]\n	%2$s -h\n"),
		cmd_opt.my_name, cmd_opt.my_name);
	}
	exit(status);
}


static char *
map_type_name_str(itmc_map_type_t type)
{
	int	i;
	for (i = 0; NULL != map_type_name[i].name; i++) {
		if (type == map_type_name[i].type) {
			return (map_type_name[i].name);
		}
	}
	return ("");
}

static void
map_name_type_append(char *optarg)
{
	char			*oa;
	char			*oa_save;
	char			*name;
	char			*p;
	char			*phf;
	int			hash_factor = 0;
	itmc_map_type_t		type;
	itmc_map_name_type_t	*m;
	int			i;

	oa = oa_save = strdup_vital(optarg);

	while ((NULL != oa) && ('\0' != *oa)) {
		name = oa;
		oa = strchr(oa, ',');
		if (NULL != oa) {
			*(oa++) = '\0';
		}
		p = strchr(name, '=');
		if (NULL == p) {
			type = ITMC_MAP_AUTOMATIC;
		} else {
			*(p++) = '\0';
			if ('\0' == *p) {
				type = ITMC_MAP_AUTOMATIC;
			} else {
				phf = strchr(p, ':');
				if (NULL != phf) {
					*(phf++) = '\0';
					hash_factor = atoi(phf);
					if (hash_factor < 0) {
						itm_error(
						gettext(
						"invalid hash factor is "
						"specified: %s\n"),
							phf);
						hash_factor = 0;
						error_deferred += 1;
					}
				}
				for (i = 0;
				    NULL != map_type_name[i].name; i++) {
					if (0 ==
					    strcmp(p, map_type_name[i].name)) {
						type = map_type_name[i].type;
						break;
					}
				}
				if (NULL == map_type_name[i].name) {
					itm_error(
					gettext(
					"unknown map type is specified: %s\n"),
					p);
					error_deferred += 1;
					continue;
				}
			}
		}
		if (0 == strcmp(name, "default")) {
			*name = '\0';
		}
		m = cmd_opt.map_name_type;
		if (NULL == m) {
			m = malloc_vital(sizeof (itmc_map_name_type_t));
			m->name = strdup_vital(name);
			m->type = type;
			m->hash_factor = hash_factor;
			m->next = NULL;
			cmd_opt.map_name_type = m;
			continue;
		}
		for (; ; m = m->next) {
			if (0 == strcmp(name, m->name)) {
				if (type == m->type) {
					m = NULL;
					break;
				}
				if ('\0' == *name) {
					itm_error(
					gettext(
					"multiple default types are specified:"
					" \"%1$s\" and \"%2$s\"\n"),
						map_type_name_str(type),
						map_type_name_str(m->type));
				} else {
					itm_error(
					gettext("map \"%1$s\" is specified as "
					"two types \"%2$s\" and \"%3$s\"\n"),
					name,
					map_type_name_str(type),
					map_type_name_str(m->type));
				}
				error_deferred += 1;
				m = NULL;
				break;
			}
			if (NULL == m->next) {
				break;
			}
		}
		if (NULL != m) {
			m->next = malloc_vital(sizeof (itmc_map_name_type_t));
			m = m->next;
			m->name = strdup_vital(name);
			m->type = type;
			m->hash_factor = hash_factor;
			m->next = NULL;

		}
	}
	free(oa_save);
}



void *
malloc_vital(size_t size)
{
	void	*p;

	TRACE_MESSAGE('M', ("malloc_vital: %d\n", size));

	size = ITMROUNDUP(size);

	p = (void*) malloc(size);
	if (NULL == p) {
		PERROR(gettext("malloc"));
		exit(ITMC_STATUS_SYS);
	}

	(void) memset(p, 0, size);

	return	(p);
}


static char *
strdup_vital(const char		*str)
{
	char	*p;
	size_t	len;

	if (NULL == str) {
		return	(NULL);
	}

	len = strlen(str) + 1;
	p = malloc_vital(len);
	(void) memcpy(p, str, len);
	return	(p);
}





itm_data_t *
str_to_data(int size, char *seq)
{
	itm_data_t *data;

	data = malloc_vital(sizeof (itm_data_t));

	data->size = size;
	if (size <= sizeof (data->place)) {
		(void) memmove(&(data->place), seq, size);
	} else {
		data->place.itm_ptr = (itm_place2_t)malloc_vital(size);
		(void) memmove((char *)(data->place.itm_ptr), seq, size);
	}

	return	(data);
}


char *
name_to_str(itm_data_t *name)
{
	static char	*ptr = NULL;
	static size_t	len = 0;
	size_t		req_len;
	char		*p;

	if (NULL == name) {
		p = gettext("(no name)");
		req_len = strlen(p) + 1;
	} else {
		req_len = name->size + 1;
	}

	if (len <= req_len) {
		len += 512;
		free(ptr);
		ptr = malloc_vital(len);
	}

	if (NULL == name) {
		(void) memcpy(ptr, p, req_len);
		*(ptr + req_len) = '\0';
	} else if (name->size <= (sizeof (name->place))) {
		(void) memcpy(ptr, (char *)(&(name->place)), name->size);
		*(ptr + name->size) = '\0';
	} else {
		(void) memcpy(ptr, (char *)(name->place.itm_ptr), name->size);
		*(ptr + name->size) = '\0';
	}

	return	(ptr);
}

#define	ARGUMENTSMAX (8)
char *
data_to_hexadecimal(itm_data_t		*data)
{
	static int index = 0;
	static char	*ptr[ARGUMENTSMAX] = { NULL, NULL, NULL, NULL,
						NULL, NULL, NULL, NULL};
	static long	len[ARGUMENTSMAX] = { 0, 0, 0, 0, 0, 0, 0, 0};
	char		*hdp;
	char		*p;
	long		i;
	int		val;
	size_t		req_len;

	if (ARGUMENTSMAX <= index) index = 0;
	req_len = (2 * data->size) + 1;
	if (len[index] <= req_len) {
		len[index] += 512;
		free(ptr[index]);
		ptr[index] = malloc_vital(len[index]);
	}
	hdp = ptr[index];

	if (data->size <= (sizeof (itm_place_t))) {
		p = (char *)&(data->place);
	} else {
		p = (char *)(data->place.itm_ptr);
	}

	for (i = 0; i < data->size; i++, p++) {
		val = ((*p & 0x00f0) >> 4);
		if ((0 <= val) && (val <= 9)) {
			*hdp = '0' + val;
		} else {
			*hdp = 'a' + val - 10;
		}
		hdp++;

		val = (*p & 0x000f);
		if ((0 <= val) && (val <= 9)) {
			*hdp = '0' + val;
		} else {
			*hdp = 'a' + val - 10;
		}
		hdp++;
	}
	*hdp = '\0';
	return (ptr[index++]);
}





void
itm_error(char *format, ...)
{
	va_list		ap;
	va_start(ap, format);

	if (0 == cmd_opt.quiet) {
		(void) vfprintf(stderr, format, ap);
	}
	va_end(ap);
}

#if defined(ENABLE_TRACE)
static void
trace_option(void)
{
	char **pp;
	int	i;

	if (!(TRACE('o')))
		return;

	itm_error("my_name	   = %s\n", cmd_opt.my_name);
	if (NULL == cmd_opt.input_file) {
		(void) fprintf(stdout, "input_file   = (stdin)\n");
	} else {
		for (pp = cmd_opt.input_file; *pp; pp++) {
			(void) fprintf(stdout, "input_file   = %s\n", *pp);
		}
	}
	itm_error("output_file  = %s\n",
		cmd_opt.output_file ? cmd_opt.output_file : "(stdout)");
	itm_error("interpreter  = %s\n",
		cmd_opt.interpreter ? cmd_opt.interpreter : "(default)");
	if (cmd_opt.cpp_opt) {
		itm_error("cpp_opt	   = %s\n", *(cmd_opt.cpp_opt));
		for (i = 1; i < cmd_opt.cpp_opt_num; i++) {
			itm_error("\t%s\n", *(cmd_opt.cpp_opt + i));
		}
	} else {
		itm_error("cpp_opt	   = %s\n", "(none)");
	}
	itm_error("preprocess_default = %s\n",
		cmd_opt.preprocess_default ? cmd_opt.preprocess_default :
		"(no)");
	itm_error("preprocess_specified = %s\n",
		cmd_opt.preprocess_specified ? cmd_opt.preprocess_specified :
		"(no)");
	itm_error("preprocess   = %s\n",
		cmd_opt.preprocess ? cmd_opt.preprocess : "(no)");
	itm_error("disassemble  = %s\n",
		cmd_opt.disassemble ? "yes" : "no");
	itm_error("map type	   =");
	if (NULL == cmd_opt.map_name_type) {
		itm_error("\n");
	} else {
		itmc_map_name_type_t *m;
		itm_error(" ");
		m = cmd_opt.map_name_type;
		itm_error("%s=%s",
			(((NULL == m->name) || ('\0' == *(m->name))) ?
				"default" : m->name),
			map_type_name_str(m->type));
		if (0 != m->hash_factor) {
			itm_error(":%ld\n", m->hash_factor);
		} else {
			(void) fputc('\n', stderr);
		}
		for (m = m->next; NULL != m; m = m->next) {
			itm_error("		%s=%s",
				(((NULL == m->name) || ('\0' == *(m->name))) ?
					"default" : m->name),
				map_type_name_str(m->type));
			if (0 != m->hash_factor) {
				itm_error(":%ld\n", m->hash_factor);
			} else {
				(void) fputc('\n', stderr);
			}
		}
	}
	itm_error("large table  = %s\n",
		cmd_opt.large_table ? "true" : "false");
	itm_error("overwrite	   = %s\n",
		cmd_opt.force_overwrite ? "true" : "false");
	itm_error("strip	      = %s\n",
		cmd_opt.strip ? "true" : "false");
	itm_error("no_output	   = %s\n",
		cmd_opt.no_output ? "true" : "false");
	itm_error("trace	      = ");
	if (NULL == cmd_opt.trace) {
		itm_error("(no)\n");
	} else {
		for (i = 0x21; i < 0x7f; i++) {
			if (TRACE(i)) {
				(void) fputc(i, stderr);
			}
		}
		(void) fputc('\n', stderr);
	}
}
#endif /* ENABLE_TRACE */

#if defined(ENABLE_TRACE)
extern void
trace_message(char *format, ...)
{
	va_list	ap;
	va_start(ap, format);

	(void) vfprintf(stderr, format, ap);

	va_end(ap);
}
#endif /* ENABLE_TRACE */
