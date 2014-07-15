/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Joyent, Inc.
 */

/*
 * This program implements a small domain-specific language (DSL) for the
 * generation of nvlists, and subsequent printing in JSON-formatted output.
 * The test suite uses this tool to drive the JSON formatting routines in
 * libnvpair(3LIB) for testing.
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <locale.h>

#include <libnvpair.h>

#define	MAX_ARGS	100
#define	CMD_NAME_LEN	50

/*
 * As we are parsing a language that allows the creation of arbitrarily nested
 * state, i.e. both nested nvlists and arrays of nested nvlists, we store that
 * state in a stack.  The top frame in the stack represents the nested nvlist
 * (or nvlists, for an array) that we are currently building.
 *
 * When creating an array, the "next" directive advances lw_pos and allocates a
 * new nvlist.  The "end" directive commits either the nvlist, or array of
 * nvlists, into the parent nvlist.  It then pops and frees the stack frame
 * before returning control to the parser.
 */

typedef struct list_wrap {
	nvlist_t *lw_nvl[MAX_ARGS];
	char *lw_name;
	int lw_pos;
	boolean_t lw_array;
	struct list_wrap *lw_next;
} list_wrap_t;

int
list_wrap_depth(list_wrap_t *lw)
{
	int d = 0;

	while (lw != NULL) {
		d++;
		lw = lw->lw_next;
	}

	return (d);
}

list_wrap_t *
list_wrap_alloc(list_wrap_t *next)
{
	list_wrap_t *out = calloc(1, sizeof (list_wrap_t));

	if (out == NULL)
		abort();

	out->lw_next = next;

	return (out);
}

list_wrap_t *
list_wrap_pop_and_free(list_wrap_t *lw)
{
	list_wrap_t *next = lw->lw_next;

	free(lw->lw_name);
	free(lw);

	return (next);
}

/*
 * Generic integer and floating point parsing routines:
 */

int
parse_int(char *in, int64_t *val, int64_t min, int64_t max)
{
	int64_t t;
	char *end = NULL;

	errno = 0;
	t = strtoll(in, &end, 10);
	if (errno != 0 || end == in || *end != '\0') {
		if (errno == ERANGE) {
			(void) fprintf(stderr, "ERROR: integer %s not in "
			    "range [%lld,%lld]\n", in, min, max);
			return (-1);
		}
		(void) fprintf(stderr, "ERROR: could not parse \"%s\" as "
		    "signed integer (%s)\n", in, strerror(errno));
		return (-1);
	}

	if (t < min || t > max) {
		(void) fprintf(stderr, "ERROR: integer %lld not in range "
		    "[%lld,%lld]\n", t, min, max);
		return (-1);
	}

	*val = t;
	return (0);
}

int
parse_uint(char *in, uint64_t *val, uint64_t min, uint64_t max)
{
	uint64_t t;
	char *end = NULL;

	errno = 0;
	t = strtoull(in, &end, 10);
	if (errno != 0 || end == in || *end != '\0') {
		if (errno == ERANGE) {
			(void) fprintf(stderr, "ERROR: integer %s not in "
			    "range [%llu,%llu]\n", in, min, max);
			return (-1);
		}
		(void) fprintf(stderr, "ERROR: could not parse \"%s\" as "
		    "unsigned integer (%s)\n", in, strerror(errno));
		return (-1);
	}

	if (t < min || t > max) {
		(void) fprintf(stderr, "ERROR: integer %llu not in range "
		    "[%llu,%llu]\n", t, min, max);
		return (-1);
	}

	*val = t;
	return (0);
}

int
parse_double(char *in, double *val)
{
	double t;
	char *end = NULL;

	errno = 0;
	t = strtod(in, &end);
	if (errno != 0 || end == in || *end != '\0') {
		(void) fprintf(stderr, "ERROR: could not parse \"%s\" as "
		    "double\n", in);
		return (-1);
	}

	*val = t;
	return (0);
}

/*
 * Command-specific handlers for directives specified in the DSL input:
 */

typedef int (*command_handler_t)(list_wrap_t **, boolean_t, int,
    char **);

static int
ch_add_string(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	if (array) {
		if (nvlist_add_string_array(nvl, argv[0], &argv[1],
		    argc - 1) != 0) {
			(void) fprintf(stderr, "fail at "
			    "nvlist_add_string_array\n");
			return (-1);
		}
	} else {
		if (nvlist_add_string(nvl, argv[0], argv[1]) != 0) {
			(void) fprintf(stderr, "fail at nvlist_add_string\n");
			return (-1);
		}
	}

	return (0);
}

static int
ch_add_boolean(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	if (array)
		abort();

	if (nvlist_add_boolean(nvl, argv[0]) != 0) {
		(void) fprintf(stderr, "fail at nvlist_add_boolean\n");
		return (-1);
	}
	return (0);
}

static int
ch_add_boolean_value(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	int i;
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];
	boolean_t arrval[MAX_ARGS];

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "true") == 0) {
			arrval[i - 1] = B_TRUE;
		} else if (strcmp(argv[i], "false") == 0) {
			arrval[i - 1] = B_FALSE;
		} else {
			(void) fprintf(stderr, "invalid boolean value: %s\n",
			    argv[i]);
			return (-1);
		}
	}

	if (array) {
		if (nvlist_add_boolean_array(nvl, argv[0], arrval,
		    argc - 1) != 0) {
			(void) fprintf(stderr, "fail at "
			    "nvlist_add_boolean_array\n");
			return (-1);
		}
	} else {
		if (nvlist_add_boolean_value(nvl, argv[0], arrval[0]) != 0) {
			(void) fprintf(stderr, "fail at "
			    "nvlist_add_boolean_value\n");
			return (-1);
		}
	}

	return (0);
}


/*
 * The confluence of a strongly typed C API for libnvpair(3LIB) and the
 * combinatorial explosion of both sizes and signedness is unfortunate.  Rather
 * than reproduce the same code over and over, this macro parses an integer,
 * checks applicable bounds based on size and signedness, and stores the value
 * (or array of values).
 */
#define	DO_CMD_NUMBER(typ, nam, min, max, ptyp, func)			\
	ptyp val;							\
	typ ## _t arrval[MAX_ARGS];					\
	int i;								\
	for (i = 1; i < argc; i++) {					\
		if (func(argv[i], &val, min, max) != 0) {		\
			return (-1);					\
		}							\
		arrval[i - 1] = (typ ## _t) val;			\
	}								\
	if (array) {							\
		if (nvlist_add_ ## nam ## _array(nvl, argv[0],		\
		    arrval, argc - 1) != 0) {				\
			(void) fprintf(stderr, "fail at "		\
			    "nvlist_add_" #nam "_array\n");		\
			return (-1);					\
		}							\
	} else {							\
		if (nvlist_add_ ## nam(nvl, argv[0],			\
		    arrval[0]) == -1) {					\
			(void) fprintf(stderr, "fail at "		\
			    "nvlist_add_" #nam "\n");			\
			return (-1);					\
		}							\
	}								\
	return (0);

static int
ch_add_byte(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(uchar, byte, 0, UCHAR_MAX, uint64_t, parse_uint)
}

static int
ch_add_int8(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(int8, int8, INT8_MIN, INT8_MAX, int64_t, parse_int)
}

static int
ch_add_uint8(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(uint8, uint8, 0, UINT8_MAX, uint64_t, parse_uint)
}

static int
ch_add_int16(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(int16, int16, INT16_MIN, INT16_MAX, int64_t, parse_int)
}

static int
ch_add_uint16(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(uint16, uint16, 0, UINT16_MAX, uint64_t, parse_uint)
}

static int
ch_add_int32(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(int32, int32, INT32_MIN, INT32_MAX, int64_t, parse_int)
}

static int
ch_add_uint32(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(uint32, uint32, 0, UINT32_MAX, uint64_t, parse_uint)
}

static int
ch_add_int64(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(int64, int64, INT64_MIN, INT64_MAX, int64_t, parse_int)
}

static int
ch_add_uint64(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];

	DO_CMD_NUMBER(uint64, uint64, 0, UINT64_MAX, uint64_t, parse_uint)
}

static int
ch_add_double(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *nvl = (*lw)->lw_nvl[(*lw)->lw_pos];
	double val;

	if (array)
		abort();

	if (parse_double(argv[1], &val) != 0) {
		return (-1);
	}

	if (nvlist_add_double(nvl, argv[0], val) != 0) {
		(void) fprintf(stderr, "fail at nvlist_add_double_value\n");
		return (-1);
	}

	return (0);
}

static int
ch_end(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	nvlist_t *parent;
	char *name;

	if (list_wrap_depth(*lw) < 2) {
		(void) fprintf(stderr, "ERROR: not nested, cannot end.\n");
		return (-1);
	}

	parent = (*lw)->lw_next->lw_nvl[(*lw)->lw_next->lw_pos];
	name = (*lw)->lw_name;
	if ((*lw)->lw_array) {
		/*
		 * This was an array of objects.
		 */
		nvlist_t **children = (*lw)->lw_nvl;
		int nelems = (*lw)->lw_pos + 1;

		if (nvlist_add_nvlist_array(parent, name, children,
		    nelems) != 0) {
			(void) fprintf(stderr, "fail at "
			    "nvlist_add_nvlist_array\n");
			return (-1);
		}
	} else {
		/*
		 * This was a single object.
		 */
		nvlist_t *child = (*lw)->lw_nvl[0];

		if ((*lw)->lw_pos != 0)
			abort();

		if (nvlist_add_nvlist(parent, name, child) != 0) {
			(void) fprintf(stderr, "fail at nvlist_add_nvlist\n");
			return (-1);
		}
	}

	*lw = list_wrap_pop_and_free(*lw);

	return (0);
}

static int
ch_next(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	if (!(*lw)->lw_array) {
		(void) fprintf(stderr, "ERROR: cannot use 'next' outside an "
		    "object array.\n");
		return (-1);
	}

	if ((*lw)->lw_pos++ >= MAX_ARGS) {
		(void) fprintf(stderr, "ERROR: object array too long\n");
		return (-1);
	}

	if (nvlist_alloc(&(*lw)->lw_nvl[(*lw)->lw_pos], NV_UNIQUE_NAME,
	    0) != 0) {
		(void) fprintf(stderr, "ERROR: failed at nvlist_alloc\n");
		return (-1);
	}

	return (0);
}

static int
ch_add_object(list_wrap_t **lw, boolean_t array, int argc, char **argv)
{
	*lw = list_wrap_alloc(*lw);

	(*lw)->lw_name = strdup(argv[0]);
	(*lw)->lw_array = array;

	if (nvlist_alloc(&(*lw)->lw_nvl[0], NV_UNIQUE_NAME, 0) != 0) {
		(void) fprintf(stderr, "fail at nvlist_alloc\n");
		return (-1);
	}

	return (0);
}

typedef struct command {
	char cmd_name[CMD_NAME_LEN];
	command_handler_t cmd_func;
	int cmd_min_args;
	int cmd_max_args;
	boolean_t cmd_array_mode;
} command_t;

/*
 * These are the commands we support in the testing DSL, and their
 * handling functions:
 */
command_t command_handlers[] = {
	{ "add_boolean", ch_add_boolean, 1, 1, B_FALSE },
	{ "add_boolean_value", ch_add_boolean_value, 2, 2, B_FALSE },
	{ "add_byte", ch_add_byte, 2, 2, B_FALSE },
	{ "add_int8", ch_add_int8, 2, 2, B_FALSE },
	{ "add_uint8", ch_add_uint8, 2, 2, B_FALSE },
	{ "add_int16", ch_add_int16, 2, 2, B_FALSE },
	{ "add_uint16", ch_add_uint16, 2, 2, B_FALSE },
	{ "add_int32", ch_add_int32, 2, 2, B_FALSE },
	{ "add_uint32", ch_add_uint32, 2, 2, B_FALSE },
	{ "add_int64", ch_add_int64, 2, 2, B_FALSE },
	{ "add_uint64", ch_add_uint64, 2, 2, B_FALSE },
	{ "add_double", ch_add_double, 2, 2, B_FALSE },
	{ "add_string", ch_add_string, 2, 2, B_FALSE },
	{ "add_object", ch_add_object, 1, 1, B_FALSE },
	{ "add_boolean_array", ch_add_boolean_value, 1, MAX_ARGS, B_TRUE },
	{ "add_byte_array", ch_add_byte, 1, MAX_ARGS, B_TRUE },
	{ "add_int8_array", ch_add_int8, 1, MAX_ARGS, B_TRUE },
	{ "add_uint8_array", ch_add_uint8, 1, MAX_ARGS, B_TRUE },
	{ "add_int16_array", ch_add_int16, 1, MAX_ARGS, B_TRUE },
	{ "add_uint16_array", ch_add_uint16, 1, MAX_ARGS, B_TRUE },
	{ "add_int32_array", ch_add_int32, 1, MAX_ARGS, B_TRUE },
	{ "add_uint32_array", ch_add_uint32, 1, MAX_ARGS, B_TRUE },
	{ "add_int64_array", ch_add_int64, 1, MAX_ARGS, B_TRUE },
	{ "add_uint64_array", ch_add_uint64, 1, MAX_ARGS, B_TRUE },
	{ "add_string_array", ch_add_string, 1, MAX_ARGS, B_TRUE },
	{ "add_object_array", ch_add_object, 1, 1, B_TRUE },
	{ "end", ch_end, 0, 0, B_FALSE },
	{ "next", ch_next, 0, 0, B_FALSE },
	{ 0 }
};

/*
 * This function determines which command we are executing, checks argument
 * counts, and dispatches to the appropriate handler:
 */
static int
command_call(list_wrap_t **lw, char *command, int argc, char **argv)
{
	int ch;

	for (ch = 0; command_handlers[ch].cmd_name[0] != '\0'; ch++) {
		if (strcmp(command, command_handlers[ch].cmd_name) != 0)
			continue;

		if (argc > command_handlers[ch].cmd_max_args ||
		    argc < command_handlers[ch].cmd_min_args) {

			(void) fprintf(stderr, "ERROR: command \"%s\""
			    " expects between %d and %d arguments,"
			    " but %d were provided.\n", command,
			    command_handlers[ch].cmd_min_args,
			    command_handlers[ch].cmd_max_args,
			    argc);

			return (-1);
		}

		return (command_handlers[ch].cmd_func(lw,
		    command_handlers[ch].cmd_array_mode, argc, argv));
	}

	(void) fprintf(stderr, "ERROR: invalid command: \"%s\"\n", command);

	return (-1);
}

/*
 * The primary state machine for parsing the input DSL is implemented in
 * this function:
 */

typedef enum state {
	STATE_REST = 1,
	STATE_COMMAND,
	STATE_ARG_FIND,
	STATE_ARG,
	STATE_ARG_ESCAPE,
	STATE_ARG_ESCAPE_HEX,
	STATE_C_COMMENT_0,
	STATE_C_COMMENT_1,
	STATE_C_COMMENT_2
} state_t;

int
parse(FILE *in, list_wrap_t **lw)
{
	char b[8192];
	int bp;
	state_t st = STATE_REST;
	int argc = 0;
	char *argv[MAX_ARGS];
	int line = 1;
	char hex[3];
	int nhex = 0;

	b[0] = '\0';
	bp = 0;

	for (;;) {
		int c = fgetc(in);

		/*
		 * Signal an error if the file ends part way through a
		 * construct:
		 */
		if (st != STATE_REST && c == EOF) {
			(void) fprintf(stderr, "ERROR: unexpected end of "
			    "file\n");
			return (-1);
		} else if (c == EOF) {
			return (0);
		}

		if (c == '\n')
			line++;

		switch (st) {
		case STATE_REST:
			if (isalpha(c) || c == '_') {
				argc = 0;
				bp = 0;
				b[bp++] = c;
				b[bp] = '\0';
				st = STATE_COMMAND;
				continue;
			} else if (c == ' ' || c == '\t' || c == '\n') {
				/*
				 * Ignore whitespace.
				 */
				continue;
			} else if (c == '/') {
				st = STATE_C_COMMENT_0;
				continue;
			} else {
				goto unexpected;
			}

		case STATE_C_COMMENT_0:
			if (c != '*') {
				goto unexpected;
			}
			st = STATE_C_COMMENT_1;
			continue;

		case STATE_C_COMMENT_1:
			if (c == '*') {
				st = STATE_C_COMMENT_2;
			}
			continue;

		case STATE_C_COMMENT_2:
			if (c == '/') {
				st = STATE_REST;
			} else if (c != '*') {
				st = STATE_C_COMMENT_1;
			}
			continue;

		case STATE_COMMAND:
			if (isalnum(c) || c == '_') {
				b[bp++] = c;
				b[bp] = '\0';
				st = STATE_COMMAND;

				continue;

			} else if (isspace(c)) {
				/*
				 * Start collecting arguments into 'b'
				 * after the command.
				 */
				st = STATE_ARG_FIND;
				bp++;

				continue;
			} else if (c == ';') {
				/*
				 * This line was _just_ a command,
				 * so break out and process now:
				 */
				goto execute;
			} else {
				goto unexpected;
			}

		case STATE_ARG_FIND:
			if (isspace(c)) {
				/*
				 * Whitespace, ignore.
				 */
				continue;

			} else if (c == ';') {
				/*
				 * Break out to process command.
				 */
				goto execute;

			} else if (c == '"') {
				st = STATE_ARG;

				argv[argc] = &b[++bp];
				b[bp] = '\0';

				continue;
			} else {
				goto unexpected;
			}

		case STATE_ARG:
			if (c == '"') {
				if (argc++ >= MAX_ARGS) {
					(void) fprintf(stderr, "ERROR: too "
					    "many args\n");
					return (-1);
				}
				st = STATE_ARG_FIND;
				continue;
			} else if (c == '\n') {
				(void) fprintf(stderr, "ERROR: line not "
				    "finished\n");
				return (-1);
			} else if (c == '\\') {
				st = STATE_ARG_ESCAPE;
				continue;
			} else {
				b[bp++] = c;
				b[bp] = '\0';
				continue;
			}

		case STATE_ARG_ESCAPE:
			if (c == 'a') {
				c = '\a';
			} else if (c == 'b') {
				c = '\b';
			} else if (c == 'f') {
				c = '\f';
			} else if (c == 'n') {
				c = '\n';
			} else if (c == 'r') {
				c = '\r';
			} else if (c == 't') {
				c = '\t';
			} else if (c == 'v') {
				c = '\v';
			} else if (c == 'x') {
				st = STATE_ARG_ESCAPE_HEX;
				hex[0] = hex[1] = hex[2] = '\0';
				nhex = 0;
				continue;
			} else if (c != '\\' && c != '"') {
				goto unexpected;
			}

			b[bp++] = c;
			b[bp] = '\0';
			st = STATE_ARG;
			continue;

		case STATE_ARG_ESCAPE_HEX:
			if (!isxdigit(c)) {
				goto unexpected;
			}
			hex[nhex] = c;
			if (nhex++ >= 1) {
				/*
				 * The hex escape pair is complete, parse
				 * the integer and insert it as a character:
				 */
				int x;
				errno = 0;
				if ((x = strtol(hex, NULL, 16)) == 0 ||
				    errno != 0) {
					goto unexpected;
				}
				b[bp++] = (char)x;
				b[bp] = '\0';
				st = STATE_ARG;
			}
			continue;
		}

		/*
		 * We do not ever expect to break out of the switch block
		 * above.  If we do, it's a programmer error.
		 */
		abort();

execute:
		if (command_call(lw, b, argc, argv) == -1)
			return (-1);

		st = STATE_REST;
		continue;

unexpected:
		(void) fprintf(stderr, "ERROR: (line %d) unexpected "
		    "character: %c\n", line, c);
		return (-1);
	}
}

/*
 * Entry point:
 */
int
main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;
	list_wrap_t *lw;

	/*
	 * Be locale-aware.  The JSON output functions will process multibyte
	 * characters in the current locale, and emit a correct JSON encoding
	 * for unprintable characters.
	 */
	if (setlocale(LC_ALL, "") == NULL) {
		(void) fprintf(stderr, "Could not set locale: %s\n",
		    strerror(errno));
		goto out;
	}

	lw = list_wrap_alloc(NULL);

	if (nvlist_alloc(&lw->lw_nvl[0], NV_UNIQUE_NAME, 0) != 0)
		goto out;

	/*
	 * Generate the list from the commands passed to us on stdin:
	 */
	if (parse(stdin, &lw) != 0)
		goto out;

	/*
	 * Print the resultant list, and a terminating newline:
	 */
	if (nvlist_print_json(stdout, lw->lw_nvl[0]) != 0 ||
	    fprintf(stdout, "\n") < 0)
		goto out;

	rc = EXIT_SUCCESS;

out:
	(void) list_wrap_pop_and_free(lw);

	return (rc);
}
