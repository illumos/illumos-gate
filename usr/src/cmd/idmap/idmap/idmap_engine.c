/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <locale.h>
#include <ctype.h>
#ifdef WITH_LIBTECLA
#include <libtecla.h>
#endif
#include "idmap_engine.h"

/* The maximal line length. Longer lines may not be parsed OK. */
#define	MAX_CMD_LINE_SZ 1023

#ifdef WITH_LIBTECLA
#define	MAX_HISTORY_LINES 1023
static GetLine * gl_h;
/* LINTED E_STATIC_UNUSED */
#endif

/* Array for arguments of the actuall command */
static char ** my_argv;
/* Allocated size for my_argv */
static int my_argv_size = 16;
/* Actuall length of my_argv */
static int my_argc;

/* Array for subcommands */
static cmd_ops_t *my_comv;
/* my_comc length */
static int my_comc;

/* Input filename specified by the -f flag */
static char *my_filename;

/*
 * Batch mode means reading file, stdin or libtecla input. Shell input is
 * a non-batch mode.
 */
static int my_batch_mode;

/* Array of all possible flags */
static flag_t flags[FLAG_ALPHABET_SIZE];

/* getopt variables */
extern char *optarg;
extern int optind, optopt, opterr;

/* Fill the flags array: */
static int
options_parse(int argc, char *argv[], const char *options)
{
	int c;

	optind = 1;

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case '?':
			return (-1);
		case ':':
	/* This is relevant only if options starts with ':': */
			(void) fprintf(stderr,
			    gettext("Option %s: missing parameter\n"),
			    argv[optind - 1]);
			return (-1);
		default:
			if (optarg == NULL)
				flags[c] = FLAG_SET;
			else
				flags[c] = optarg;

		}
	}
	return (optind);
}

/* Unset all flags */
static void
options_clean()
{
	(void) memset(flags, 0, FLAG_ALPHABET_SIZE * sizeof (flag_t));
}

/* determine which subcommand is argv[0] and execute its handler */
static int
run_command(int argc, char **argv, cmd_pos_t *pos)
{
	int i;

	if (argc == 0) {
		if (my_batch_mode)
			return (0);
		return (-1);
	}
	for (i = 0; i < my_comc; i++) {
		int optind;
		int rc;

		if (strcmp(my_comv[i].cmd, argv[0]) != 0)
			continue;

		/* We found it. Now execute the handler. */
		options_clean();
		optind = options_parse(argc, argv, my_comv[i].options);
		if (optind < 0) {
			return (-1);
		}

		rc = my_comv[i].p_do_func(flags,
		    argc - optind,
		    argv + optind,
		    pos);

		return (rc);
	}

	(void) fprintf(stderr, gettext("Unknown command %s\n"),
	    argv[0]);

	return (-1);

}

/*
 * Read another parameter from "from", up to a space char (unless it
 * is quoted). Duplicate it to "to". Remove quotation, if any.
 */
static int
get_param(char **to, const char *from)
{
	int to_i, from_i;
	char c;
	int last_slash = 0; 	/* Preceded by a slash? */
	int in_string = 0;	/* Inside quites? */
	int is_param = 0;
	size_t buf_size = 20;	/* initial length of the buffer. */
	char *buf = (char *)malloc(buf_size * sizeof (char));

	from_i = 0;
	while (isspace(from[from_i]))
		from_i++;

	for (to_i = 0; '\0' != from[from_i]; from_i++) {
		c = from[from_i];

		if (to_i >= buf_size - 1) {
			buf_size *= 2;
			buf = (char *)realloc(buf, buf_size * sizeof (char));
		}

		if (c == '"' && !last_slash) {
			in_string = !in_string;
			is_param = 1;
			continue;

		} else if (c == '\\' && !last_slash) {
			last_slash = 1;
			continue;

		} else if (!last_slash && !in_string && isspace(c)) {
			break;
		}

		buf[to_i++] = from[from_i];
		last_slash = 0;

	}

	if (to_i == 0 && !is_param) {
		free(buf);
		*to = NULL;
		return (0);
	}

	buf[to_i] = '\0';
	*to = buf;

	if (in_string)
		return (-1);

	return (from_i);
}

/*
 * Split a string to a parameter array and append it to the specified position
 * of the array
 */
static int
line2array(const char *line)
{
	const char *cur;
	char *param;
	int len;

	for (cur = line; len = get_param(&param, cur); cur += len) {
		if (my_argc >= my_argv_size) {
			my_argv_size *= 2;
			my_argv = (char **)realloc(my_argv,
			    my_argv_size * sizeof (char *));
		}

		my_argv[my_argc] = param;
		++my_argc;

		/* quotation not closed */
		if (len < 0)
			return (-1);

	}
	return (0);

}

/* Clean all aruments from my_argv. Don't deallocate my_argv itself. */
static void
my_argv_clean()
{
	int i;
	for (i = 0; i < my_argc; i++) {
		free(my_argv[i]);
		my_argv[i] = NULL;
	}
	my_argc = 0;
}


#ifdef WITH_LIBTECLA
/* This is libtecla tab completion. */
static
CPL_MATCH_FN(command_complete)
{
	/*
	 * WordCompletion *cpl; const char *line; int word_end are
	 * passed from the CPL_MATCH_FN macro.
	 */
	int i;
	char *prefix;
	int prefix_l;

	/* We go on even if quotation is not closed */
	(void) line2array(line);


	/* Beginning of the line: */
	if (my_argc == 0) {
		for (i = 0; i < my_comc; i++)
			(void) cpl_add_completion(cpl, line, word_end,
			    word_end, my_comv[i].cmd, "", " ");
		goto cleanup;
	}

	/* Is there something to complete? */
	if (isspace(line[word_end - 1]))
		goto cleanup;

	prefix = my_argv[my_argc - 1];
	prefix_l = strlen(prefix);

	/* Subcommand name: */
	if (my_argc == 1) {
		for (i = 0; i < my_comc; i++)
			if (strncmp(prefix, my_comv[i].cmd, prefix_l) == 0)
				(void) cpl_add_completion(cpl, line,
				    word_end - prefix_l,
				    word_end, my_comv[i].cmd + prefix_l,
				    "", " ");
		goto cleanup;
	}

	/* Long options: */
	if (prefix[0] == '-' && prefix [1] == '-') {
		char *options2 = NULL;
		char *paren;
		char *thesis;
		int i;

		for (i = 0; i < my_comc; i++)
			if (0 == strcmp(my_comv[i].cmd, my_argv[0])) {
				options2 = strdup(my_comv[i].options);
				break;
			}

		/* No such subcommand, or not enough memory: */
		if (options2 == NULL)
			goto cleanup;

		for (paren = strchr(options2, '(');
		    paren && ((thesis = strchr(paren + 1, ')')) != NULL);
		    paren = strchr(thesis + 1, '(')) {
		/* Short option or thesis must precede, so this is safe: */
			*(paren - 1) = '-';
			*paren = '-';
			*thesis = '\0';
			if (strncmp(paren - 1, prefix, prefix_l) == 0) {
				(void) cpl_add_completion(cpl, line,
				    word_end - prefix_l,
				    word_end, paren - 1 + prefix_l, "", " ");
			}
		}
		free(options2);

		/* "--" is a valid completion */
		if (prefix_l == 2) {
			(void) cpl_add_completion(cpl, line,
			    word_end - 2,
			    word_end, "", "", " ");
		}

	}

cleanup:
	my_argv_clean();
	return (0);
}

/* libtecla subshell: */
static int
interactive_interp()
{
	int rc = 0;
	char *prompt;
	const char *line;

	(void) sigset(SIGINT, SIG_IGN);

	gl_h = new_GetLine(MAX_CMD_LINE_SZ, MAX_HISTORY_LINES);

	if (gl_h == NULL) {
		(void) fprintf(stderr,
		    gettext("Error reading terminal: %s.\n"),
		    gl_error_message(gl_h, NULL, 0));
		return (-1);
	}

	(void) gl_customize_completion(gl_h, NULL, command_complete);

	for (;;) {
new_line:
		my_argv_clean();
		prompt = "> ";
continue_line:
		line = gl_get_line(gl_h, prompt, NULL, -1);

		if (line == NULL) {
			switch (gl_return_status(gl_h)) {
			case GLR_SIGNAL:
				gl_abandon_line(gl_h);
				goto new_line;

			case GLR_EOF:
				(void) line2array("exit");
				break;

			case GLR_ERROR:
				(void) fprintf(stderr,
				    gettext("Error reading terminal: %s.\n"),
				    gl_error_message(gl_h, NULL, 0));
				rc = -1;
				goto end_of_input;
			default:
				(void) fprintf(stderr, "Internal error.\n");
				exit(1);
			}
		} else {
			if (line2array(line) < 0) {
				(void) fprintf(stderr,
				    gettext("Quotation not closed\n"));
				goto new_line;
			}
			if (my_argc == 0) {
				goto new_line;
			}
			if (strcmp(my_argv[my_argc-1], "\n") == 0) {
				my_argc--;
				free(my_argv[my_argc]);
				(void) strcpy(prompt, "> ");
				goto continue_line;
			}
		}

		rc = run_command(my_argc, my_argv, NULL);

		if (strcmp(my_argv[0], "exit") == 0 && rc == 0) {
			break;
		}

	}

end_of_input:
	gl_h = del_GetLine(gl_h);
	my_argv_clean();
	return (rc);
}
#endif

/* Interpretation of a source file given by "name" */
static int
source_interp(const char *name)
{
	FILE *f;
	int is_stdin;
	int rc = -1;
	char line[MAX_CMD_LINE_SZ];
	cmd_pos_t pos;

	if (name == NULL || strcmp("-", name) == 0) {
		f = stdin;
		is_stdin = 1;
	} else {
		is_stdin = 0;
		f = fopen(name, "r");
		if (f == NULL) {
			perror(name);
			return (-1);
		}
	}

	pos.linenum = 0;
	pos.line = line;

	while (fgets(line, MAX_CMD_LINE_SZ, f)) {
		pos.linenum ++;

		if (line2array(line) < 0) {
			(void) fprintf(stderr,
			    gettext("Quotation not closed\n"));
			my_argv_clean();
			continue;
		}

		/* We do not wan't "\n" as the last parameter */
		if (my_argc != 0 && strcmp(my_argv[my_argc-1], "\n") == 0) {
			my_argc--;
			free(my_argv[my_argc]);
			continue;
		}

		if (my_argc != 0 && strcmp(my_argv[0], "exit") == 0) {
			rc = 0;
			my_argv_clean();
			break;
		}

		rc = run_command(my_argc, my_argv, &pos);
		my_argv_clean();
	}

	if (my_argc > 0) {
		(void) fprintf(stderr, gettext("Line continuation missing\n"));
		rc = 1;
		my_argv_clean();
	}

	if (!is_stdin)
		(void) fclose(f);

	return (rc);
}

/*
 * Initialize the engine.
 * comc, comv is the array of subcommands and its length,
 * argc, argv are arguments to main to be scanned for -f filename and
 *    the length og the array,
 * is_batch_mode passes to the caller the information if the
 *    batch mode is on.
 *
 * Return values:
 * 0: ... OK
 * IDMAP_ENG_ERROR: error and message printed already
 * IDMAP_ENG_ERROR_SILENT: error and message needs to be printed
 *
 */

int
engine_init(int comc, cmd_ops_t *comv, int argc, char **argv,
    int *is_batch_mode)
{
	int c;

	my_comc = comc;
	my_comv = comv;

	my_argc = 0;
	my_argv = (char **)calloc(my_argv_size, sizeof (char *));

	if (argc < 1) {
		my_filename = NULL;
		if (isatty(fileno(stdin))) {
#ifdef WITH_LIBTECLA
			my_batch_mode = 1;
#else
			my_batch_mode = 0;
			return (IDMAP_ENG_ERROR_SILENT);
#endif
		} else
			my_batch_mode = 1;

		goto the_end;
	}

	my_batch_mode = 0;

	optind = 0;
	while ((c = getopt(argc, argv,
	    "f:(command-file)")) != EOF) {
		switch (c) {
		case '?':
			return (IDMAP_ENG_ERROR);
		case 'f':
			my_batch_mode = 1;
			my_filename = optarg;
			break;
		default:
			(void) fprintf(stderr, "Internal error.\n");
			exit(1);
		}
	}

the_end:

	if (is_batch_mode != NULL)
		*is_batch_mode = my_batch_mode;
	return (0);
}

/* finitialize the engine */
int
engine_fini()
{
	my_argv_clean();
	free(my_argv);
	return (0);
}

/*
 * Interpret the subcommands defined by the arguments, unless
 * my_batch_mode was set on in egnine_init.
 */
int
run_engine(int argc, char **argv)
{
	int rc = -1;

	if (my_batch_mode) {
#ifdef WITH_LIBTECLA
		if (isatty(fileno(stdin)))
			rc = interactive_interp();
		else
#endif
			rc = source_interp(my_filename);
		goto cleanup;
	}

	rc = run_command(argc, argv, NULL);

cleanup:
	return (rc);
}
